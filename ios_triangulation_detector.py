#!/usr/bin/env python3 
# Checks full iOS filesystem images for traces of compromise by Operation Triangulation
# Based on Kaspersky's triangle_check tool (© 2023 AO Kaspersky Lab. All Rights Reserved)

import ios_triangulation_detector.__main__ as m

if __name__ == "__main__":
    m.main()
