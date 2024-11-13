project(
  'amd-bmc-ras',
  'cpp',
  default_options: [
    'warning_level=3',
    'werror=true',
    'cpp_std=c++23'
  ],
  license: 'Apache-2.0',
  version: '1.0',
)


conf_data = configuration_data()

# Define the directory paths
ras_dir = '/var/lib/amd-ras/'
index_file = '/var/lib/amd-ras/current_index'
config_file = '/var/lib/amd-ras/ras_config.json'

cpp_args = [
  '-DRAS_DIR="' + ras_dir + '"',
  '-DINDEX_FILE="' + index_file + '"',
  '-DCONFIG_FILE="' + config_file + '"'
]

cpp = meson.get_compiler('cpp')

# Meson requires an absolute path for find_library().
libdir = meson.current_source_dir() + './lib/'

apml_dep = cpp.find_library('apml64', dirs : libdir) # ./lib/libapml64.lib
cper_dep = cpp.find_library('cper-generate',dirs : libdir)
boost_dep = dependency('boost')

deps = [
  dependency('libgpiodcxx', default_options: ['bindings=cxx']),
  dependency('nlohmann_json'),
  dependency('phosphor-logging'),
  dependency('sdbusplus'),
  dependency('sdeventplus'),
  dependency('systemd'),
  dependency('threads'),
  apml_dep,
  cper_dep,
  boost_dep,
]

apml = get_option('apml-interface')
if apml
  add_project_arguments('-DAPML', language: 'cpp')
endif

pldm = get_option('pldm-interface')
if pldm
  add_project_arguments('-DPLDM', language: 'cpp')
endif

executable(
  'amd-bmc-ras',
  'src/apml_manager.cpp',
  'src/config_manager.cpp',
  'src/cper_generator.cpp',
  'src/interface_manager_base.cpp',
  'src/main.cpp',
  include_directories: include_directories('inc'),
  cpp_args: cpp_args,
  dependencies: deps,
  install: true,
  install_dir: get_option('bindir'))

ras_config_dir = join_paths(get_option('datadir'), 'ras-config')
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

