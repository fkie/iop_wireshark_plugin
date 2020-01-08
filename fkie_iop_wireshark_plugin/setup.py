#!/usr/bin/env python

from distutils.core import setup

scripts=['scripts/run_parser.py']
packages=['fkie_iop_wireshark_plugin']
package_dir={'': 'src'}

try:
   from catkin_pkg.python_setup import generate_distutils_setup

   d = generate_distutils_setup(
      ##  don't do this unless you want a globally visible script
      scripts=scripts,
      packages=packages,
      package_dir=package_dir
   )

   setup(**d)
except ImportError:
   # install without catkin
   setup(name='fkie_iop_wireshark_plugin',
         version='1.0.0',
         license='Apache-2.0',
         description='Wireshark dissector for IOP',
         author='Alexander Tiderko',
         author_email='alexander.tiderko@fkie.fraunhofer.de',
         url='https://github.com/fkie/iop_node_manager',
         install_requires=['python-pyxb'],
         scripts=scripts,
         packages=packages,
         package_dir=package_dir
   )
