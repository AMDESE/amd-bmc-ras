project(
  'amd-ras-manager',
  'cpp',
  default_options: [
    'warning_level=3',
    'werror=true',
    'cpp_std=c++23'
  ],
  license: 'Apache-2.0',
  version: '1.0',
)

config_file = '/var/lib/amd-bmc-ras/ras_config.json'
src_config_file = '/usr/share/amd-bmc-ras/ras_config.json'
cpp_args = [
  '-DCONFIG_FILE="' + config_file + '"',
  '-DSRC_CONFIG_FILE="' + src_config_file + '"'
]

boost_args = [
    '-DBOOST_ALL_NO_LIB',
    '-DBOOST_ASIO_DISABLE_THREADS',
    '-DBOOST_ERROR_CODE_HEADER_ONLY',
    '-DBOOST_NO_RTTI',
    '-DBOOST_NO_TYPEID',
    '-DBOOST_SYSTEM_NO_DEPRECATED',
]

deps = [
    dependency('boost'),
    dependency('phosphor-dbus-interfaces'),
    dependency('phosphor-logging'),
    dependency('sdbusplus'),
    dependency('libsystemd'),
    dependency('nlohmann_json', include_type: 'system'),
]

sources = [
  'src/config_manager.cpp',
  'src/main.cpp',
]

executable(
  'amd-ras-manager',
  sources,
  include_directories: include_directories('include'),
  dependencies: deps,
  cpp_args: cpp_args + boost_args,
  install: true,
  install_dir: get_option('bindir'))

ras_config_dir = join_paths(get_option('datadir'), 'amd-bmc-ras')
install_data(
    join_paths(meson.current_source_dir(), 'config', 'ras_config.json'),
    install_dir: ras_config_dir,
    rename: 'ras_config.json'
)

systemd = dependency('systemd')

install_data(
  ['service_files/com.amd.RAS.service'],
  install_dir: systemd.get_pkgconfig_variable('systemdsystemunitdir')
)
