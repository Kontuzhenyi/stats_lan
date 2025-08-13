#!/bin/bash
cd /home/viktor/stats_lan/network_stats_web
source venv/bin/activate
python manage.py runserver 0.0.0.0:8000
