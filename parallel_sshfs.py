import posixpath
import secrets
import shlex
import stat
import threading
import weakref
from contextlib import ExitStack, contextmanager
from datetime import datetime

from fsspec.spec import AbstractBufferedFile, AbstractFileSystem
from funcy import wrap_with
from pssh.clients import SSHClient
from ssh2.error_codes import LIBSSH2_ERROR_EAGAIN
from ssh2.exceptions import SSH2Error
from ssh2.sftp import (
    LIBSSH2_FXF_CREAT,
    LIBSSH2_FXF_READ,
    LIBSSH2_FXF_WRITE,
    LIBSSH2_SFTP_S_IRGRP,
    LIBSSH2_SFTP_S_IROTH,
    LIBSSH2_SFTP_S_IRUSR,
    LIBSSH2_SFTP_S_IWUSR,
)

_READ_MODE = LIBSSH2_FXF_READ
_READ_FLAGS = LIBSSH2_SFTP_S_IRUSR

_WRITE_MODE = LIBSSH2_FXF_CREAT | LIBSSH2_FXF_WRITE
_WRITE_FLAGS = (
    LIBSSH2_SFTP_S_IRUSR
    | LIBSSH2_SFTP_S_IWUSR
    | LIBSSH2_SFTP_S_IRGRP
    | LIBSSH2_SFTP_S_IROTH
)

_HANDLE_ARGS = {
    "rb": (_READ_MODE, _READ_FLAGS),
    "wb": (_WRITE_MODE, _WRITE_FLAGS),
}


def get_temp_filename():
    return f".tmp.{secrets.token_hex(24)}"


class SSHFileSystem(AbstractFileSystem):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._connect(kwargs)

    def _finalize(self, client):
        client.disconnect()

    def _connect(self, auth_options):
        self.client = SSHClient(**auth_options)
        self._free_channels = []

        weakref.finalize(self, self._finalize, self.client)

    def _check_exists(self, path):
        if not self.exists(path):
            raise FileNotFoundError(path)

    def _check_not_exists(self, path):
        if self.exists(path):
            raise FileExistsError(path)

    def _decode_attributes(self, attributes):
        if stat.S_ISDIR(attributes.permissions):
            kind = "directory"
        elif stat.S_ISREG(attributes.permissions):
            kind = "file"
        elif stat.S_ISLNK(attributes.permissions):
            kind = "link"
        else:
            kind = "unknown"

        out = {
            "size": attributes.filesize,
            "type": kind,
            "gid": attributes.gid,
            "uid": attributes.uid,
            "time": datetime.utcfromtimestamp(attributes.atime),
            "mtime": datetime.utcfromtimestamp(attributes.mtime),
        }
        return out

    @wrap_with(threading.RLock())
    def info(self, path):
        try:
            attributes = self.sftp("stat", path)
        except SSH2Error as exc:
            # TODO: try to find a way to distungish this
            # from other likely errors
            raise FileNotFoundError(path) from exc

        details = self._decode_attributes(attributes)
        details["name"] = path
        return details

    def mkdir(self, path, mode=511):
        try:
            self._check_not_exists(path)
        except FileExistsError:
            return None

        self.sftp("mkdir", path, mode)

    def makedirs(self, path, exist_ok=False, mode=511):
        try:
            self._check_not_exists(path)
        except FileExistsError:
            if exist_ok:
                return None
            else:
                raise

        start, *parts = path.split("/")
        base_parts = [start]
        for part in parts:
            base_parts.append(part)
            self.mkdir("/".join(base_parts))

    def rmdir(self, path):
        self._check_exists(path)

        self.sftp("rmdir", path)

    def _rm(self, path):
        self._check_exists(path)

        if self.isdir(path):
            self.sftp("rmdir", path)
        else:
            self.sftp("unlink", path)

    def mv(self, lpath, rpath):
        # rename_ex is weirdly buggy with flags, so
        # we have to use rename with an extra exists
        # call.
        self._check_exists(lpath)
        self._check_not_exists(rpath)

        self.sftp("rename", lpath, rpath)

    def ls(self, path, detail=False):
        self._check_exists(path)

        handle = self.sftp("opendir", path)
        listings = []
        for _, name, attributes in handle.readdir():
            if name in [b"", b".", b".."]:
                continue

            listing = self._decode_attributes(attributes)
            listing["name"] = posixpath.join(path, name.decode())
            listings.append(listing)

        if detail:
            return listings
        else:
            return [listing["name"] for listing in listings]

    def cp_file(self, lpath, rpath, **kwargs):
        self._check_exists(lpath)

        args = ["cp"]
        args.append(shlex.quote(lpath))
        args.append(shlex.quote(rpath))

        self.makedirs(self._parent(rpath), exist_ok=True)
        result = self.client.run_command(" ".join(args))
        errors = "".join(result.stderr)
        if errors:
            raise ValueError(f"cp_file failed: {errors!r}")

    def sftp(self, method, *args, **kwargs):
        with self.get_sftp_channel() as channel:
            func = getattr(channel, method)
            return self.run_func(func, *args, **kwargs)

    def run_func(self, func, *args, **kwargs):
        return self.client._eagain(func, *args, **kwargs)

    def _open(
        self, path, mode="rb", block_size=None, autocommit=True, **kwargs
    ):
        return SSHFile(self, path, mode, block_size, autocommit, **kwargs)

    @contextmanager
    def get_sftp_channel(self):
        # TODO: limit the number of open sftp channels
        if not self._free_channels:
            # TODO: create a bunch of sftp connections to cache
            self._free_channels.append(self.client._make_sftp())

        try:
            channel = self._free_channels.pop()
            yield channel
        finally:
            self._free_channels.append(channel)


class SSHFile(AbstractBufferedFile):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.mode not in {"rb", "wb"}:
            raise NotImplementedError

        args = _HANDLE_ARGS.get(self.mode)
        if args is None:
            raise NotImplementedError(
                f"File open mode {self.mode!r} is not supported"
            )

        if "w" in self.mode:
            self.fs.makedirs(self.fs._parent(self.path), exist_ok=True)
            self._tmp_path = posixpath.join(
                self.fs._parent(self.path), get_temp_filename()
            )
        else:
            self._tmp_path = self.path

        self._stack = ExitStack()
        channel = self._stack.enter_context(self.fs.get_sftp_channel())
        _raw_handle = self.fs.client._sftp_openfh(
            channel.open, self._tmp_path, *args
        )
        self._handle = self._stack.enter_context(_raw_handle)

    def _upload_chunk(self, final=False):
        self.buffer.seek(self.offset)
        self.fs.client.eagain_write(self._handle.write, self.buffer.read())
        if final and self.autocommit:
            self.commit()

    def commit(self):
        try:
            self.fs.copy(self._tmp_path, self.path)
        finally:
            self.fs.rm(self._tmp_path)

    def _read_all(self):
        data = b""
        for size, chunk in self._handle:
            if size == LIBSSH2_ERROR_EAGAIN:
                self.fs.client.poll()
                continue
            data += chunk
        return data

    def _read_partial(self, length):
        chunk = b""
        while True:
            size, data = self._handle.read(length)
            if size == -37:
                self.fs.client.poll()
                continue
            elif not data:
                break
            chunk += data
        return chunk

    def read(self, length=-1):
        if length == -1:
            chunk = self._read_all()
        else:
            chunk = self._read_partial(length)

        if length != -1 and len(chunk) > length:
            chunk = chunk[:length]
            self._handle.seek(self.loc + length)

        self.loc += len(chunk)
        return chunk

    def close(self):
        self._stack.close()
        super().close()
