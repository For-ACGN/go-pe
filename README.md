# go-pe
copy from https://github.com/saferwall/pe and made minor improvements.

## Improvement
1. remove mmap package for cross-compilation
2. rewrite function about get system certificate for remove package os/exec
3. rewrite default logger, not output data to os.Stdout
