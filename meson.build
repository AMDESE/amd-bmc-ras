project(
  'amd-ras',
  'cpp',
  default_options: [
    'warning_level=3',
    'werror=true',
    'cpp_std=c++17'
  ],
  license: 'Apache-2.0',
  version: '1.0',
)


conf_data = configuration_data()
conf_data.set_quoted('DBUS_OBJECT_NAME', 'com/amd/crashdump')
conf_data.set_quoted('DBUS_SERVICE_NAME','com.amd.crashdump')

cpp_args = []

cpp = meson.get_compiler('cpp')

configure_file(output: 'config.h',
  configuration: conf_data
)

# (Meson requires an absolute path for find_library().)
libdir = meson.current_source_dir() + './lib/'

apml_dep = cpp.find_library('apml64', dirs : libdir) # ./lib/libapml64.lib

deps = [
  dependency('libgpiodcxx', default_options: ['bindings=cxx']),
  dependency('systemd'),
  dependency('sdbusplus'),
  dependency('sdeventplus'),
  dependency('phosphor-logging'),
  dependency('nlohmann_json'),
  dependency('threads'),
  apml_dep,
]

executable(
  'amd-ras',
  'src/main.cpp',
  'src/runtime_errors.cpp',
  'src/write_cper_data.cpp',
  'src/dbus_ras.cpp',
  'src/fatal_error.cpp',
  'src/Config.cpp',
  include_directories: include_directories('inc'),
  cpp_args: cpp_args,
  dependencies: deps,
  install: true,
  install_dir: get_option('bindir'))

systemd = dependency('systemd')

install_data(
  ['service_files/com.amd.crashdump.service'],
  install_dir: systemd.get_pkgconfig_variable('systemdsystemunitdir')
)

