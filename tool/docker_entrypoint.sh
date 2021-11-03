#!/usr/bin/env sh

/app/app -port "${PORT}" -secret "${KUBERNETES_SECRET_NAME}" $@
