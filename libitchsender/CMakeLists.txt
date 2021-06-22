file(GLOB SRCS *.cpp *.h)

add_library(itchsender STATIC ${SRCS})

target_include_directories(itchsender PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(itchsender ${CMAKE_THREAD_LIBS_INIT} Boost::system)
