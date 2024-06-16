project(
    'cryptopals',
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
    add_project_arguments(extra_args, language: ['cpp'])
endif

gtest_dep = dependency('gtest')
openssl_dep = dependency('openssl')
include_dirs = include_directories('include')

t = executable(
    'test_crypto',
    sources: ['tests/test_crypto.cpp'],
    dependencies: [gtest_dep],
    include_directories: include_dirs,
)
test('test_crypto', t, workdir: meson.current_source_dir())

subdir('set1')
subdir('set2')