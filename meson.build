project(
  'amd-bmc-ras',
  'cpp',
  default_options: [
    'warning_level=3',
    'werror=true',
    'cpp_std=c++20'
  ],
  license: 'Apache-2.0',
  version: '1.0',
)


conf_data = configuration_data()

cpp_args = []

cpp = meson.get_compiler('cpp')

# (Meson requires an absolute path for find_library().)
libdir = meson.current_source_dir() + './lib/'

apml_dep = cpp.find_library('apml64', dirs : libdir) # ./lib/libapml64.lib
cper_dep = cpp.find_library('cper-generate',dirs : libdir)

deps = [
  dependency('libgpiodcxx', default_options: ['bindings=cxx']),
  dependency('systemd'),
  dependency('sdbusplus'),
  dependency('sdeventplus'),
  dependency('phosphor-logging'),
  dependency('nlohmann_json'),
  dependency('threads'),
  apml_dep,
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

executable(
  'amd-bmc-ras',
  'src/main.cpp',
  'src/apml_manager.cpp',
  'src/interface_manager_base.cpp',
  'src/config_manager.cpp',
  include_directories: include_directories('inc'),
  cpp_args: cpp_args,
  dependencies: deps,
  install: true,
  install_dir: get_option('bindir'))

ras_config_dir = join_paths(get_option('datadir'), 'ras-config')
install_data(
    join_paths(meson.current_source_dir(), 'config', 'ras-config.json'),
    install_dir: ras_config_dir,
    rename: 'ras-config.json'
)

systemd = dependency('systemd')

install_data(
  ['service_files/com.amd.RAS.service'],
  install_dir: systemd.get_pkgconfig_variable('systemdsystemunitdir')
)

