# parallel-sshfs

An unmaintained fsspec implementation for the ssh/sftp
protocol via using  [parallel-ssh](https://github.com/ParallelSSH/parallel-ssh).

## Disclaimer

I didn't spend a lot of time on this project,
it was just test to see how good parallel ssh
performs in our use case though I wasn't able
to run the benchmarks due to various errors. I
also have to note that this implementation depends
on various internal methods of parallel-ssh (like
`_eagain`, `_make_sftp`) and undocumented public
methods (like `eagain_write`). I couldn't find
a public API to cover all the operations I needed
so just be aware.

You might encounter with different sorts of
errors from different places, some might arise
on race conditions and others just happen randomly.
Here are a few that I stumbled against;

- When writing to a stream it might poll
indefinitely and never continue
- When writing to a stream sometimes it just
hits an assertion in the underlying libssh2
library (the C one, not the python-binding)
and gets a core dump.
- There is a double free happening that I
didn't try to deduce at which point, though
I suspect might be a race condition (? even
then it shouldn't happen).

Other stuff to note;
- Since all sftp errors throw a generic error,
we have to waste a couple exists() calls for each
operation to ensure `FileNotFoundError`s are properly
delegated. This is costful and also doesn't guarantee
much since you might still hit other sorts of errors
which are nearly indistungishable.
- No kerberos/gss auth for the ssh2, though just to
note parallel-ssh claims they are available on the
other client.

