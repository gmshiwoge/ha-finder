add_executable(haos_diagnostic_helper
  "haos_diagnostic_helper.cpp"
)

apply_standard_settings(haos_diagnostic_helper)
target_compile_options(haos_diagnostic_helper PRIVATE /utf-8)
target_compile_definitions(haos_diagnostic_helper PRIVATE "NOMINMAX" "WIN32_LEAN_AND_MEAN")
target_link_libraries(haos_diagnostic_helper PRIVATE "ws2_32.lib" "iphlpapi.lib")
target_link_options(haos_diagnostic_helper PRIVATE
  "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
)
