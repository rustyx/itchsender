file(GLOB SRCS *.cpp *.h)

add_executable(main ${SRCS})

target_link_libraries(main itchsender Boost::program_options Boost::date_time Boost::regex Boost::iostreams)

if(WIN32)
  target_link_libraries(main winmm.lib)
endif()

set_target_properties(main PROPERTIES OUTPUT_NAME itchsender)

install(TARGETS main DESTINATION bin)
