FROM python:alpine as base

FROM base as builder
RUN mkdir /install
WORKDIR /install
COPY . /src
RUN pip install --prefix=/install /src

FROM base
RUN adduser -u 1000 -h /scans -s /bin/false -D python && \
        install -d -m 0755 -o python -g python /config
COPY --from=builder /install /usr/local
USER python
WORKDIR /scans
ENV DOXIEAPI_CONFIG_PATH /config/doxieapi.ini

ENTRYPOINT ["python", "-m", "doxieapi"]
