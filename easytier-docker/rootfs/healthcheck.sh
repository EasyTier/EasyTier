#!/bin/sh
s6-svstat /run/s6-rc/servicedirs/easytier || exit 1