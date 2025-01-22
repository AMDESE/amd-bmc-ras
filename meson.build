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
gpio_config_file = '/var/lib/amd-bmc-ras/gpio_config.json'
src_config_file = '/usr/share/amd-bmc-ras/ras_config.json'
src_gpio_config_file = '/usr/share/amd-bmc-ras/gpio_config.json'

ras_dir = '/var/lib/amd-bmc-ras/'
index_file = '/var/lib/amd-bmc-ras/current_index'
cpp_args = [
  '-DCONFIG_FILE="' + config_file + '"',
  '-DGPIO_CONFIG_FILE="' + gpio_config_file + '"',
  '-DSRC_CONFIG_FILE="' + src_config_file + '"',
  '-DINDEX_FILE="' + index_file + '"',
  '-DSRC_CONFIG_FILE="' + src_config_file + '"',
  '-DSRC_GPIO_CONFIG_FILE="' + src_gpio_config_file + '"',
  '-DRAS_DIR="' + ras_dir + '"',
]

libdir = meson.current_source_dir() + './lib/'
cpp = meson.get_compiler('cpp')
apml_dep = cpp.find_library('apml64', dirs : libdir)
cper_dep = dependency('libcper', include_type: 'system')

boost_args = [
    '-DBOOST_ALL_NO_LIB',
    '-DBOOST_ASIO_DISABLE_THREADS',
    '-DBOOST_ERROR_CODE_HEADER_ONLY',
    '-DBOOST_NO_RTTI',
    '-DBOOST_NO_TYPEID',
    '-DBOOST_SYSTEM_NO_DEPRECATED',
]

deps = [
    dependency('libgpiodcxx', default_options: ['bindings=cxx']),
    dependency('boost'),
    dependency('phosphor-dbus-interfaces'),
    dependency('phosphor-logging'),
    dependency('sdbusplus'),
    dependency('libsystemd'),
    dependency('nlohmann_json', include_type: 'system'),
    cper_dep,
]

apml = get_option('apml-interface')
if apml
  add_project_arguments('-DAPML', language: 'cpp')
endif

pldm = get_option('pldm-interface')
if pldm
  add_project_arguments('-DPLDM', language: 'cpp')
endif

sources = [
  'src/config_manager.cpp',
  'src/main.cpp',
  'src/error_monitor.cpp',
  'src/apml_manager.cpp',
  'src/utils/util.cpp',
  'src/utils/dbus_util.cpp',
  'src/utils/cper_util.cpp',
  'src/utils/host_util.cpp',
  'src/utils/hex_util.cpp',
  'src/crashdump_manager.cpp',
]

if apml
  sources += 'src/apml_manager.cpp'
  deps += apml_dep
endif

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

install_data(
    join_paths(meson.current_source_dir(), 'config', 'gpio_config.json'),
    install_dir: ras_config_dir,
    rename: 'gpio_config.json'
)

systemd = dependency('systemd')

install_data(
  ['service_files/com.amd.RAS.service'],
  install_dir: systemd.get_pkgconfig_variable('systemdsystemunitdir')
)
