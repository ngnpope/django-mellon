#!/bin/sh

set -e -x
env
if [ -f /var/lib/jenkins/pylint.django.rc ]; then
	PYLINT_RC=/var/lib/jenkins/pylint.django.rc
elif [ -f pylint.django.rc ]; then
	PYLINT_RC=pylint.django.rc
else
	echo No pylint RC found
	exit 0
fi
pylint -f parseable --rcfile ${PYLINT_RC} "$@" | tee pylint.out || /bin/true
