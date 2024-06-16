srcs = [
    'challenge9',
    'challenge10',
    'challenge11',
    'challenge12',
]

foreach s : srcs
    e = executable(
        s,
        sources: [s + '.cpp'],
        dependencies: [gtest_dep, openssl_dep],
        include_directories: include_dirs,
    )
    test(s, e, workdir: meson.current_source_dir())
endforeach