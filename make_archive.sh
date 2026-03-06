#!/bin/bash
cd /home/kimocoder/wifite2
tar czf /home/kimocoder/wifite2_archive.tar.gz --exclude='.git' --exclude='__pycache__' --exclude='.pytest_cache' .
echo "Archive created: /home/kimocoder/wifite2_archive.tar.gz"
ls -la /home/kimocoder/wifite2_archive.tar.gz
