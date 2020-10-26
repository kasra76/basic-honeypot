#!/bin/bash

#curl --data "username=$1&email=$2&password=$3" http://localhost:8000/register/user/
curl --data "username=$1&email=$2&phone_number=$3&password=$4" http://185.205.209.236:8000/register/user/
