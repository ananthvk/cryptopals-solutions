# cryptopals-solutions

This repo contains my solutions to [https://cryptopals.com/](https://cryptopals.com/) challenges.

## How to run

Firstly, install [meson](https://github.com/mesonbuild/meson) and [ninja](https://github.com/ninja-build/ninja)

Clone the repository

```
$ git clone https://github.com/ananthvk/cryptopals-solutions
$ cd cryptopals-solutions
```

Then build and run the tests

```
$ meson setup builddir
$ cd builddir
$ ninja -j8 test
```