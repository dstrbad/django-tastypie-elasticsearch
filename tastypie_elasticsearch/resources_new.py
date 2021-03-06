# -*- coding: utf-8 -*-
"""
tastypie.Resource definitions for Elasticsearch

"""

import re
import sys
import json
from copy import deepcopy

from django.conf import settings
from django.conf.urls import url
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned, ValidationError

from tastypie import http
from tastypie.bundle import Bundle
from tastypie.fields import NOT_PROVIDED
from tastypie.resources import Resource, DeclarativeMetaclass, convert_post_to_patch
from tastypie.exceptions import NotFound, ImmediateHttpResponse
from tastypie.utils import dict_strip_unicode_keys, trailing_slash

import elasticsearch
import elasticsearch.exceptions
from elasticsearch.connection import Urllib3HttpConnection

from paginator import ElasticsearchResult, ElasticsearchPaginator

import elasticutils as eslib
from elasticutils import S, F

class ElasticsearchDeclarativeMetaclass(DeclarativeMetaclass):
    """
    This class has the same functionality as its supper ``ModelDeclarativeMetaclass``.
    Changing only some Elasticsearch intrinsics
    """

    def __new__(self, name, bases, attrs):
        meta = attrs.get('Meta')

        new_class = super(ElasticsearchDeclarativeMetaclass,
            self).__new__(self, name, bases, attrs)

        override = {
            'object_class': dict,
            'include_mapping_fields': True,
            'paginator_class': ElasticsearchPaginator,
        }
        defaults = {
            'es_server': getattr(settings, "ES_URL", "127.0.0.1:9200"),
            'es_connection_class': Urllib3HttpConnection,
            'es_timeout': 30,
            'create_if_missing': False,
            'index_settings': {},
            'write_index': None,
        }
        for k,v in override.iteritems():
            setattr(new_class._meta, k, v)

        for k,v in defaults.iteritems():
            if not hasattr(new_class._meta, k):
                setattr(new_class._meta, k, v)

        return new_class

class ElasticsearchResource(Resource):
    """
    Elasticsearch Base Resource

    """

    __metaclass__ = ElasticsearchDeclarativeMetaclass

    def __init__(self, api_name=None, *args, **kwargs):
        super(ElasticsearchResource, self).__init__(api_name, *args, **kwargs)

        if self._meta.write_index is None:
            self._meta.write_index =  self._meta.index

        if self._meta.create_if_missing:
            # create the index if missing and create_if_missing
            if not self.client.indices.exists(self._meta.write_index):
                self.client.indices.create(self._meta.write_index, body=self._meta.index_settings)

            # create the alias if missing and create_if_missing
            if (self._meta.write_index != self._meta.index and
                    not self.client.indices.exists_alias(self._meta.index,
                                                         self._meta.write_index)):
                self.client.indices.put_alias(self._meta.write_index, self._meta.index)

    _es = None
    def es__get(self):
        if self._es is None:
            hosts = []
            for server in self._meta.es_server.split(","):
                host, port = server.strip().split(":")
                hosts.append({"host":host, "port":port})

            self._es = elasticsearch.Elasticsearch(hosts=hosts,
                                                   connection_class=self._meta.es_connection_class,
                                                   timeout=self._meta.es_timeout)
        return self._es
    client = property(es__get)

    def prepend_urls(self):
        """Override Resource url map to fit search Id syntax"""
        resource_name = self._meta.resource_name
        tr = trailing_slash()
        return [
            # percolate implementation
            url(r"^(?P<resource_name>%s)/percolate%s$" % (resource_name, tr),
                self.wrap_view('get_percolate'), name="api_get_percolate"),

            # default implementation
            url(r"^(?P<resource_name>%s)%s$" % (resource_name, tr),
                self.wrap_view('dispatch_list'), name="api_dispatch_list"),
            url(r"^(?P<resource_name>%s)/schema%s$" % (resource_name, tr),
                self.wrap_view('get_schema'), name="api_get_schema"),
            url(r"^(?P<resource_name>%s)/set/(?P<%s_list>.*?)%s$" % (resource_name,
                self._meta.detail_uri_name, tr), self.wrap_view('get_multiple'),
                name="api_get_multiple"),
            url(r"^(?P<resource_name>%s)/(?P<%s>.*?)%s$" % (resource_name,
                self._meta.detail_uri_name, tr), self.wrap_view('dispatch_detail'),
                name="api_dispatch_detail"),
        ]

    def build_schema(self):
        schema = super(ElasticsearchResource, self).build_schema()

        if self._meta.include_mapping_fields:
            mapping = self.client.indices.get_mapping(self._meta.index, self._meta.doc_type)
            mapping_fields = mapping[self._meta.doc_type]["properties"]

            fields = schema["fields"]

            for key, v in mapping_fields.iteritems():
                if key not in fields:
                    fields[key] = {
                        "blank": v.get("default", True),
                        "default": v.get("default", None),
                        "help_text": v.get("help_text", key),
                        "nullable": v.get("nullable", "unknown"),
                        "readonly": v.get("readonly", True),
                        "unique": v.get("unique", key in ["id",]),
                        "type": v.get("type", "unknown"),
                    }
            schema["fields"] = fields

        return schema

    def full_dehydrate(self, bundle, for_list=False):
        bundle = super(ElasticsearchResource, self).full_dehydrate(bundle, for_list)

        kwargs = dict(resource_name=self._meta.resource_name, pk=bundle.obj.get("_id"))
        if self._meta.api_name is not None:
            kwargs['api_name'] = self._meta.api_name
        bundle.data["resource_uri"] = self._build_reverse_url('api_dispatch_detail', kwargs=kwargs)

        bundle.data.update(bundle.obj.get("_source", bundle.obj.get("fields")))

        bundle.data['id'] = bundle.obj['_id']

        return bundle

    def full_hydrate(self, bundle):
        bundle = super(ElasticsearchResource, self).full_hydrate(bundle)
        bundle.obj.update(bundle.data)
        return bundle

    def get_resource_uri(self, bundle_or_obj=None):
        if bundle_or_obj is None:
            result = super(ElasticsearchResource, self).get_resource_uri(bundle_or_obj)
            return result


        obj = (bundle_or_obj.obj if
            isinstance(bundle_or_obj, Bundle) else bundle_or_obj)

        kwargs = {
            'resource_name': self._meta.resource_name,
            'pk': obj.get('_id'),
        }
        if self._meta.api_name is not None:
            kwargs['api_name'] = self._meta.api_name

        return self._build_reverse_url("api_dispatch_detail", kwargs=kwargs)

    def get_sorting(self, request, key="order_by"):
        order_by = request.GET.get(key)
        if order_by:
            l = []

            items = [i.strip() for i in order_by.split(",")]
            for item in items:
                order = "asc"
                if item.startswith("-"):
                    item = item[1:]
                    order = "desc"
                l.append({item:order})
            return l
        return None

    def build_query(self, request):
        sort = self.get_sorting(request)
        query = []

        for key, value in request.GET.items():
            if key not in ["offset", "limit", "query_type", "format", 'order_by', 'email__istartswith', "anonymous"]:
                q = {".".join([self._meta.doc_type, key]): value}
                query.append({"text":q})

        if len(query) is 0:
            # show all
            query.append({"match_all": {}})

        result = {
            "from": long(request.GET.get("offset", 0)),
            "size": long(request.GET.get("limit", self._meta.limit)),
            "email__istartswith": request.GET.get("email__istartswith", None),
            "anon": request.GET.get("anonymous", "true"),
            "wid": request.GET.get("wid"),
            "sort": sort or [],
        }
        # extend result dict if body is present
        if request.body:
            result.update(json.loads(request.body))

        return result

    def get_object_list(self, request):
        kwargs = dict()
        kwargs['body'] = self.build_query(request)

        try:
           # order_by, suggest
           # u zasebnu funkciju pa pozvat
           basic_s = S().es(urls=settings.ES_URL).indexes('go_' + kwargs['body']['wid']).doctypes('subscribers')
           # index zasebna funkcija kojoj se preda wid pa ovisno o tome koji env doda prefix

            # build query funkcija
            start = kwargs['body']['from']
            end = kwargs['body']['size'] + start

            if kwargs['body']['email__istartswith']:
                # build query, vrati slozeno, ulacani query i ovdje se onda samo izvrsi
                result = basic_s[0:10].query(email__prefix=kwargs['body']['email__istartswith']).order_by('email').execute()
            else:
                result = basic_s[start:end].filter(anonymous=kwargs['body']['anon']).order_by('email').execute()
            #result = self.client.search(self._meta.index, self._meta.doc_type, **kwargs)
        except Exception, exc:
            response = http.HttpBadRequest(str(exc), content_type="text/plain")
            raise ImmediateHttpResponse(response)
        else:
            return ElasticsearchResult(result.response, kwargs)

    def obj_get_list(self, request=None, **kwargs):
        # Filtering disabled for brevity...
        return self.get_object_list(kwargs['bundle'].request)

    def obj_get(self, request=None, **kwargs):
        pk = kwargs.get("pk")
        try:
            result =  self.client.get(self._meta.index, pk, self._meta.doc_type)
        except elasticsearch.exceptions.NotFoundError, exc:
            response = http.HttpNotFound("Not found", content_type="text/plain")
            raise ImmediateHttpResponse(response)
        except Exception, exc:
            msg = "%s(%s)" % (exc.__class__.__name__, exc)
            response = http.HttpApplicationError(msg, content_type="text/plain")
            raise ImmediateHttpResponse(response)
        else:
            return result

    def get_percolate(self, request, **kwargs):
        """ Percolate call """
        self.method_check(request, allowed=['post'])
        self.is_authenticated(request)
        self.throttle_check(request)

        # Do the query.
        result = self.client.percolate(self._meta.index, self._meta.doc_type,
                                        body=dict(doc=json.loads(request.body)))
        object_list = {
            'meta': result,
        }

        self.log_throttled_access(request)
        return self.create_response(request, object_list)


