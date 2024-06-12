project(
    'dsa',
    'cpp',
    version: '0.1',
    default_options: ['warning_level=3', 'cpp_std=c++14'],
)
if meson.get_compiler('cpp').get_id() == 'clang'
    extra_args = [
        '-Wall',
        '-Wformat=2',
        '-Wshadow',
        '-Wfloat-equal',
        '-Wshift-overflow',
        '-Wextra',
        '-Wconversion',
        '-Wsign-conversion',
        '-Wcast-align',
        '-pedantic',
        '-gdwarf-4',
        '-O',
        '-fsanitize=integer,address,undefined,integer-divide-by-zero,shift,null,return,signed-integer-overflow,float-divide-by-zero,float-cast-overflow,bounds,alignment,vptr,leak',
        '-pedantic',
        '-Wno-sign-compare',
        '-Wno-unused-parameter',
        '-Wno-sign-conversion',
        '-ftrapv',
        '-D_GLIBCXX_DEBUG',
        '-D_GLIBCXX_DEBUG_PEDANTIC',
        '-D_FORTIFY_SOURCE=2',
        '-fstack-protector',
    ]
else
    extra_args = []
endif

gtest_dep = dependency('gtest')
openssl_dep = dependency('openssl')

srcs = [
    'challenge1',
    'challenge2',
    'challenge3',
    'challenge4',
    'challenge5',
    'challenge6',
    'challenge7',
    'challenge8'
]

foreach s : srcs
    e = executable(
        s,
        sources: ['set1/' + s + '.cpp'],
        dependencies: [gtest_dep, openssl_dep],
        include_directories: ['include'],
        cpp_args: extra_args,
    )
    test(s, e, workdir: meson.current_source_dir())
endforeach

t = executable(
    'test_crypto',
    sources: ['tests/test_crypto.cpp'],
    dependencies: [gtest_dep],
    include_directories: ['include'],
    cpp_args: extra_args,
)
test('test_crypto', t, workdir: meson.current_source_dir())