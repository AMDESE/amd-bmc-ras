project(
    'amd-ras-manager',
    'cpp',
    default_options: [
        'warning_level=3',
        'werror=true',
        'cpp_std=c++23',
        # PLDM event payload hex dump (pldm_event_monitor); override with -Dpldm_event_payload_hex_log=false
        'pldm_event_payload_hex_log=true',
    ],
    license: 'Apache-2.0',
    version: '1.0',
)

config_file = get_option('config_file')
platform_default_file = get_option('platform_default_file')
src_platform_default_file = get_option('src_platform_default_file')
src_config_file = get_option('src_config_file')
ras_dir = get_option('ras_dir')
oob_mode_file = get_option('oob_mode_file')
index_file = get_option('index_file')
pldm_event_message_signature = get_option('pldm_event_message_signature')
pldm_event_max_payload = get_option('pldm_event_max_payload')
pldm_event_payload_hex_log = get_option('pldm_event_payload_hex_log')
pldm_event_payload_hex_bytes_per_line = get_option('pldm_event_payload_hex_bytes_per_line')
if pldm_event_payload_hex_bytes_per_line < 1
    error('pldm_event_payload_hex_bytes_per_line must be >= 1')
endif
_pldm_match_custom = get_option('pldm_event_match')
# D-Bus match uses single quotes; building that string in Meson is error-prone. Either pass a full
# rule via pldm_event_match, or pass interface/member and compose in C++ (pldm_event_monitor.cpp).
pldm_cpp_args = [
    '-DPLDM_EVENT_MESSAGE_SIGNATURE="' + pldm_event_message_signature + '"',
    '-DPLDM_EVENT_MAX_PAYLOAD=' + pldm_event_max_payload.to_string(),
    '-DPLDM_EVENT_PAYLOAD_HEX_LOG=' + (pldm_event_payload_hex_log ? '1' : '0'),
    '-DPLDM_EVENT_PAYLOAD_HEX_BYTES_PER_LINE=' + pldm_event_payload_hex_bytes_per_line.to_string(),
]
if _pldm_match_custom != ''
    pldm_cpp_args += ['-DPLDM_EVENT_DBUS_MATCH="' + _pldm_match_custom + '"']
else
    pldm_cpp_args += [
        '-DPLDM_EVENT_INTERFACE="' + get_option('pldm_event_interface') + '"',
        '-DPLDM_EVENT_MEMBER="' + get_option('pldm_event_member') + '"',
    ]
endif

cpp_args = [
    '-DCONFIG_FILE="' + config_file + '"',
    '-DPLATFORM_DEFAULT_FILE="' + platform_default_file + '"',
    '-DSRC_PLATFORM_DEFAULT_FILE="' + src_platform_default_file + '"',
    '-DSRC_CONFIG_FILE="' + src_config_file + '"',
    '-DINDEX_FILE="' + index_file + '"',
    '-DRAS_DIR="' + ras_dir + '"',
    '-DOOB_MODE_FILE="' + oob_mode_file + '"',
] + pldm_cpp_args

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
    apml_dep,
]

apml_nda = get_option('apml-nda')
if apml_nda
    add_project_arguments('-DAPML_NDA', language: 'cpp')
endif

sources = [
    'src/config_manager.cpp',
    'src/main.cpp',
    'src/base_manager.cpp',
    'src/host_lifecycle_monitor.cpp',
    'src/apml_manager.cpp',
    'src/pldm_manager.cpp',
    'src/pldm_event_monitor.cpp',
    'src/ras_manager_factory.cpp',
    'src/utils/util.cpp',
    'src/utils/cper.cpp',
    'src/crashdump_manager.cpp',
]

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
    [
        join_paths(meson.current_source_dir(), 'config', 'ras_config.json'),
        join_paths(meson.current_source_dir(), 'config', 'platform_default.json'),
        join_paths(meson.current_source_dir(), 'config', 'amd_ras_gpio_config0.json'),
        join_paths(meson.current_source_dir(), 'config', 'amd_ras_gpio_config1.json'),
        join_paths(meson.current_source_dir(), 'config', 'amd_ras_gpio_config2.json'),
        join_paths(meson.current_source_dir(), 'config', 'oob_mode.json'),
    ],
    install_dir: ras_config_dir
)

systemd = dependency('systemd')

install_data(
    ['service_files/com.amd.RAS@.service'],
    install_dir: systemd.get_pkgconfig_variable('systemdsystemunitdir'),
)
