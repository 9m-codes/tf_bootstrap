#!/bin/bash

PROJECTS_PATH=projects
PROJECT_FILE_EXIST="$(find projects -type f | grep '\.prj')"
if [ "${PROJECT_FILE_EXIST}" == "" ]; then
  echo "No project file found."
  exit
else
  if [ -e /usr/bin/dos2unix ]; then
    /usr/bin/dos2unix -q projects/*.prj
  else
    yum -y install dos2unix
    /usr/bin/dos2unix -q projects/*.prj
  fi

  CHECK_DUPLICATES=$(sort ${PROJECTS_PATH}/*.prj | grep ^PROJECT_NAME= | awk '{print $1}' | uniq -D | wc -l)

  if [ ${CHECK_DUPLICATES} -gt 1 ]; then
    echo "There are duplicate project names. Please fix."
    exit
  fi

  PROJECTS_FILES=$(ls ${PROJECTS_PATH}/*.prj)

  for FILE in ${PROJECTS_FILES}; do
    PROJECT_NAME="$(cat ${FILE} | grep ^PROJECT_NAME= | awk -F= '{print $2}' | tr -d '"')"
    ENVIRONMENTS="$(cat ${FILE} | grep ^PROJECT_ENVS= | awk -F= '{print $2}' | tr -d '"')"
    echo ""
    echo "--------------------------------------------------------------------"
    echo ""
    if [ "${PROJECT_NAME}" == "" ] || [ "${ENVIRONMENTS}" == "" ]; then
      echo ""
      echo "Projects or Environment definition is not found in ${FILE}"
      echo "--------------------------------------------------------------------"
      echo ""
      exit
    else
      for ENV in ${ENVIRONMENTS}; do
        echo "Creating bootstrap for ${PROJECT_NAME} : ${ENV}"
        sh scripts/create_bootstrap.sh -p ${PROJECT_NAME} -e ${ENV} -c create
        echo ""
        echo "--------------------------------------------------------------------"
      done
    fi
  done
fi