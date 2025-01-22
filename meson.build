project(
    'amd-ras-manager',
    'cpp',
    default_options: ['warning_level=3', 'werror=true', 'cpp_std=c++23'],
    license: 'Apache-2.0',
    version: '1.0',
)

config_file = get_option('config_file')
platform_default_file = get_option('platform_default_file')
src_platform_default_file = get_option('src_platform_default_file')
gpio_config_file = get_option('gpio_config_file')
src_config_file = get_option('src_config_file')
src_gpio_config_file = get_option('src_gpio_config_file')
ras_dir = get_option('ras_dir')
index_file = get_option('index_file')

cpp_args = [
    '-DCONFIG_FILE="' + config_file + '"',
    '-DGPIO_CONFIG_FILE="' + gpio_config_file + '"',
    '-DPLATFORM_DEFAULT_FILE="' + platform_default_file + '"',
    '-DSRC_PLATFORM_DEFAULT_FILE="' + src_platform_default_file + '"',
    '-DSRC_CONFIG_FILE="' + src_config_file + '"',
    '-DINDEX_FILE="' + index_file + '"',
    '-DSRC_CONFIG_FILE="' + src_config_file + '"',
    '-DSRC_GPIO_CONFIG_FILE="' + src_gpio_config_file + '"',
    '-DRAS_DIR="' + ras_dir + '"',
]

libdir = meson.current_source_dir() + './lib/'
cpp = meson.get_compiler('cpp')
apml_dep = cpp.find_library('apml64', dirs: libdir)

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
    'src/base_manager.cpp',
    'src/apml_manager.cpp',
    'src/utils/util.cpp',
    'src/utils/cper.cpp',
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
    install_dir: get_option('bindir'),
)

ras_config_dir = join_paths(get_option('datadir'), 'amd-bmc-ras')
install_data(
    join_paths(meson.current_source_dir(), 'config', 'ras_config.json'),
    install_dir: ras_config_dir,
    rename: 'ras_config.json',
)

install_data(
    join_paths(meson.current_source_dir(), 'config', 'platform_default.json'),
    install_dir: ras_config_dir,
    rename: 'platform_default.json',
)

install_data(
    join_paths(meson.current_source_dir(), 'config', 'amd_ras_gpio_config.json'),
    install_dir: ras_config_dir,
    rename: 'amd_ras_gpio_config.json',
)

systemd = dependency('systemd')

install_data(
    ['service_files/com.amd.RAS.service'],
    install_dir: systemd.get_pkgconfig_variable('systemdsystemunitdir'),
)
