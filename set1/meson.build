srcs = [
    'challenge1',
    'challenge2',
    'challenge3',
    'challenge4',
    'challenge5',
    'challenge6',
    'challenge7',
    'challenge8',
]

foreach s : srcs
    e = executable(
        s,
        sources: [s + '.cpp'],
        dependencies: [gtest_dep, openssl_dep],
        include_directories: include_dirs,
        cpp_args: extra_args,
    )
    test(s, e, workdir: meson.current_source_dir())
endforeach

message('Hello this is subdir')