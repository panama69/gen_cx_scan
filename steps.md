1. pull the image
2. podman run -it --rm --entrypoint /bin/sh <image>
   this will let you into the image to search for all the *.jar files to see which folders they may be in
3. use the command in the list_packages.sh file to check what package are in the *.jar files
4. run
   python3 gen_cx_scan.py --image <image> --project <proj name> --branch <branch name> --cx-path <path to cx> --folders "<folder>"
