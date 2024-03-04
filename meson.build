project(
    'amd-bmc-ras',
    'cpp',
    default_options: [
        'warning_level=3',
        'cpp_std=c++23'
    ],
    license: 'Apache-2.0',
    version: '0.1',
    meson_version: '>=1.1.1',
)

cpp = meson.get_compiler('cpp')
libdir = meson.current_source_dir() + './lib/'
apml_dep = cpp.find_library('apml64', dirs : libdir) # ./lib/libapml64.lib

deps = [
  dependency('libgpiodcxx', default_options: ['bindings=cxx']),
  dependency('systemd'),
  dependency('sdbusplus'),
  dependency('phosphor-logging'),
  dependency('phosphor-dbus-interfaces'),
  dependency('boost'),
  dependency('threads'),
  dependency('nlohmann_json', include_type: 'system'),
  apml_dep,
]

hostInterface = get_option('host-interface')

if hostInterface == 'apml'
    subdir('apml')
endif

executable(
  'amd-bmc-ras',
  'src/main.cpp',
  interface_src_files,
  include_directories: include_directories('include',interface_includes),
  dependencies: deps,
  install: true,
  install_dir: get_option('bindir'))

systemd = dependency('systemd')
if systemd.found()
  install_data(
    'service_files/com.amd.crashdump.service',
    install_dir: systemd.get_variable('systemdsystemunitdir'))
endif
