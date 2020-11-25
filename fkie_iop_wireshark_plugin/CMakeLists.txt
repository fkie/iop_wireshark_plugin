cmake_minimum_required(VERSION 3.0.2)
project(fkie_iop_wireshark_plugin)

find_package(catkin REQUIRED COMPONENTS rospy)

###################################
## catkin specific configuration ##
###################################
catkin_python_setup()
catkin_package(
)

include(cmake/jsidl_pyxb.cmake)
generate_jsidl_pyxb()

install(
   FILES
        src/${PROJECT_NAME}/fkie_iop_template.lua
   DESTINATION ${CATKIN_PACKAGE_PYTHON_DESTINATION}
)

catkin_install_python(
    PROGRAMS 
        scripts/iop_create_dissector.py
    DESTINATION ${CATKIN_PACKAGE_BIN_DESTINATION}
)
