FROM python:latest

RUN pip install poetry uwsgi

RUN mkdir -p /work
WORKDIR /work/
RUN useradd uwsgi -d /work
RUN chown -R uwsgi:uwsgi /work
USER uwsgi

COPY pyproject.toml /work/pyproject.toml
COPY poetry.lock /work/poetry.lock

RUN poetry install

COPY app.py /work/app.py
COPY config.json /work/config.json
COPY rs256.rsa /work/rs256.rsa
COPY rs256.rsa.pub /work/rs256.rsa.pub
COPY oidc-guest-provider.uwsgi.ini /work/oidc-guest-provider.uwsgi.ini

USER root
RUN chown -R uwsgi:uwsgi /work
USER uwsgi

CMD ["uwsgi", "--ini", "/work/oidc-guest-provider.uwsgi.ini"]
