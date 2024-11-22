import contextlib
from django.conf import settings
from rest_framework import pagination, response
from rest_framework import response
from rest_framework.exceptions import NotFound
from django.core.paginator import Page as DjangoPage, InvalidPage


class Pagination(pagination.PageNumberPagination):
    max_page_size = settings.MAXIMUM_PAGE_SIZE
    page_size = settings.DEFAULT_PAGE_SIZE
    page_size_query_param = 'page_size'
    def __init__(self, results_key) -> None:
        self.results_key = results_key
        super().__init__()

    def paginate_queryset(self, queryset, request, view=None):
        with contextlib.suppress(NotFound):
            return super().paginate_queryset(queryset, request, view)
        self.page = DjangoPage([], -1, self)
        return []
    
    def paginate_queryset(self, queryset, request, view=None):
        """
        Paginate a queryset if required, either returning a
        page object, or `None` if pagination is not configured for this view.
        """
        self.request = request
        page_size = self.get_page_size(request)
        if not page_size:
            return None

        paginator = self.django_paginator_class(queryset, page_size)
        page_number = self.get_page_number(request, paginator)

        try:
            self.page = paginator.page(page_number)
        except InvalidPage as exc:
            if isinstance(page_number, str):
                page_number = int(page_number) if page_number.isdigit() else -1
            self.page = DjangoPage([], page_number, paginator)

        return list(self.page)
    
    def get_paginated_response(self, data):
        
        return response.Response({
            'page_size': self.get_page_size(self.request),
            'page_number': self.page.number,
            'page_results_count': len(self.page),
            'total_results_count': self.page.paginator.count,
            self.results_key: data,
        })

    def get_paginated_response_schema(self, schema):
        return {
            'type': 'object',
            'required': ['total_results_count', self.results_key],
            'properties': {
                'page_size': {
                    'type': 'integer',
                    'example': self.max_page_size,
                },
                'page_number': {
                    'type': 'integer',
                    'example': 3,
                },
                'page_results_count': {
                    'type': 'integer',
                    'example': self.max_page_size,
                },
                'total_results_count': {
                    'type': 'integer',
                    'example': 3,
                },
                self.results_key: schema,
            },
        }

    def __call__(self, *args, **kwargs):
        return self.__class__(results_key=self.results_key)
