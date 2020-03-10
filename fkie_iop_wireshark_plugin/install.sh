command -v pyxbgen >/dev/null 2>&1 || { echo >&2 "pyxbgen required but it's not installed. install python-pyxb first.  Aborting."; exit 1; }

DIR=$(dirname "$0")
if [ "$DIR" != "." ]; then
  echo "go first to the location the script located in!";
  exit 1;
fi

JSIDL_DIR=$1
if [ -z "$JSIDL_DIR" ]; then
    echo "use catkin_find to find jsidls in 'fkie_iop_builder' package..."
    JSIDL_DIR=$(eval catkin_find fkie_iop_builder jsidl)
    if [ -z "$JSIDL_DIR" ]; then
      echo "no path to jsidl files found!"
      echo "  -> use first parameter to set manually"
      exit 1
    fi
    echo "JSIDL found in: $JSIDL_DIR"
fi

WIRESHARK_PLUGIN_DIR=$2
if [ -z "$WIRESHARK_PLUGIN_DIR" ]; then
    WIRESHARK_PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins"
    echo "use wireshark plugin directory: $WIRESHARK_PLUGIN_DIR"
    echo "  -> second parameter to change wireshark parameter"
fi

echo "generate PYXB files to build/jsidl_pyxb"
GEN_DIR=build/jsidl_pyxb
mkdir -p $GEN_DIR
pyxbgen -u jsidl_plus.xsd --schema-root=xsd --binding-root=$GEN_DIR -m jsidl
touch $GEN_DIR/__init__.py

echo "generate lua file from JSIDL files, write to: $WIRESHARK_PLUGIN_DIR/fkie_iop.lua"
export PYTHONPATH="$PYTHONPATH:$PWD/$(dirname $GEN_DIR)/:$PWD/src/"
python scripts/iop_create_dissector.py --input_path $JSIDL_DIR --output_path $WIRESHARK_PLUGIN_DIR/fkie_iop.lua --exclude urn.jaus.jss.core-v1.0

