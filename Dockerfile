#FROM tiangolo/uvicorn-gunicorn-fastapi:python3.7

FROM python:3.7

#RUN pip3 install fastapi uvicorn

#ARG APP_USER=app
#RUN groupadd -r ${APP_USER} && useradd -m -g ${APP_USER} ${APP_USER}
#
## set environment variables
#ENV PYTHONDONTWRITEBYTECODE 1
#ENV PYTHONUNBUFFERED 1
#RUN export AUTHLIB_INSECURE_TRANSPORT=1
#
## install psycopg2 dependencies
#RUN apt-get update && apt-get install -y python3-psycopg2 apache2 apache2-dev
ENV AUTHLIB_INSECURE_TRANSPORT 1
# copy project
RUN mkdir /code
WORKDIR /code

#RUN chown app:app /code
RUN /usr/local/bin/python -m pip install --upgrade pip

COPY requirements.txt /code/requirements.txt
RUN pip3 install -r requirements.txt

COPY . /code

EXPOSE 5000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000", "--reload"]