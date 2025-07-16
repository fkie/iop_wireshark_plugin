cmake_minimum_required(VERSION 3.7)
project(fkie_iop_wireshark_plugin)

if(POLICY CMP0057)
    cmake_policy(SET CMP0057 NEW)
endif()

find_package(ament_cmake QUIET)

if ( ament_cmake_FOUND )

    add_definitions( -DUSING_ROS2 )
    message(STATUS "-----------------------------------------\nfkie_iop_wireshark_plugin is being built using AMENT.\n-----------------------------------------")

    # Install Python modules
    ament_python_install_package(${PROJECT_NAME})
    include(cmake/jsidl_pyxb.cmake)
    generate_jsidl_pyxb()
    ament_package()

    install(
        PROGRAMS
            scripts/iop_create_dissector.py
        DESTINATION lib/${PROJECT_NAME}
    )
    install(
        FILES
            ${PROJECT_NAME}/fkie_iop_template.lua
        DESTINATION lib/${PROJECT_NAME}
    )

elseif( CATKIN_DEVEL_PREFIX OR CATKIN_BUILD_BINARY_PACKAGE)

    message(STATUS "------------------------------------------\nfkie_iop_wireshark_plugin is being built using CATKIN.\n------------------------------------------")

    find_package(catkin REQUIRED)

    catkin_python_setup()
    include(cmake/jsidl_pyxb.cmake)
    generate_jsidl_pyxb()
    catkin_package()

    catkin_install_python(
        PROGRAMS 
            scripts/iop_create_dissector.py
        DESTINATION ${CATKIN_PACKAGE_BIN_DESTINATION}
    )

    install(
        FILES
            ${PROJECT_NAME}/fkie_iop_template.lua
        DESTINATION ${CATKIN_PACKAGE_PYTHON_DESTINATION}
    )
endif()
