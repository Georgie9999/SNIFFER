#!/bin/sh
g++ main.cpp -lpcap -lboost_log -lboost_system -lboost_thread -lpthread -o main 
sudo ./main
