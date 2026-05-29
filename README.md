# IOP Wireshark Plugin

## Summary

The **IOP [Wireshark][wireshark] Plugin** allows deeps inspection into [IOP][iop] messages. This is done by auto-generated [LUA][lua] script from JSIDL files. JSIDL stands for JAUS Service Interface Definition Language and contains also message definitions used to generate wireshark dissectors.

This package contains no JSIDL files. You can find such files in [JausToolsSet][jts] or [ROS/IOP Bridge][ros_iop_bridge]. Without JSIDL files only the IOP header will be parsed.

![Example Image](iop_packet_example.png)

## Install wireshark plugin

copy fkie_iop.lua to $HOME/.local/lib/wireshark/plugins/

## Build wireshark plugin

We use [PyXB-X](https://github.com/renalreg/PyXB-X) to generate python code for XMLSchema of JSIDL. Install dependencies:
```bash
pip install PyXB-X
```

Clone this repository to your preferred destination.

```bash
git clone https://github.com/fkie/iop_wireshark_plugin
```

### As ROS package inside ROS environment

If you use it with ROS put this repository into ROS workspace and call  

  ```bash
  colcon build --packages-up-to fkie_iop_wireshark_plugin
  ```

### As standalone package

Use setup.py to install the code:

  ```bash
  cd iop_wireshark_plugin/fkie_iop_wireshark_plugin
  pip install . --break-system-packages
  ```

  The executable **iop_create_dissector.py** is now located in `~/.local/bin`.

  **Note:** to remove installed files call

  ```bash
  pip uninstall fkie_iop_wireshark_plugin --break-system-packages
  ```

## Generate wireshark plugin

Run **iop_create_dissector.py** to generate the Lua script.

In ROS environment you can do it by

```bash
ros2 run fkie_iop_wireshark_plugin iop_create_dissector.py
```

otherwise

```bash
python3 ~/.local/bin/iop_create_dissector.py
```

If no path for JSIDL files is given the script tries to find the `fkie_iop_builder` ROS package from [ROS/IOP Bridge][ros_iop_bridge]. If path not found only dissector for IOP header will be generated. You can change this path with `--input_path`.

By default, the plugin is written to the file `~/.local/lib/wireshark/plugins/fkie_iop.lua`. You can change it by `--output_path`.

You can exclude subfolder from parsing if they contain different versions of the same message, e.g.

```bash
rosrun fkie_iop_wireshark_plugin iop_create_dissector.py --exclude urn.jaus.jss.core-v1.0
```

## Usage

Type `iop` into filter line in wireshark to display only IOP messages.

You can also filter for specific messages by ID or name, e.g.

`iop.message_name == "QueryIdentification"`

See **Wireshark - Display Filter Expression** window for other filter options.


[wireshark]: https://www.wireshark.org
[iop]: https://en.wikipedia.org/wiki/UGV_Interoperability_Profile
[lua]: https://www.lua.org
[jts]: https://github.com/jaustoolset/jaustoolset
[ros_iop_bridge]: https://github.com/fkie/iop_core
[pyxb]: https://pypi.org/project/PyXB
