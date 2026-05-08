import contextlib
from urllib import parse as urlparse
from django.conf import settings
from rest_framework import pagination, response
from rest_framework import response
from rest_framework.exceptions import NotFound
from django.core.paginator import Page as DjangoPage, InvalidPage

from django.core.exceptions import ImproperlyConfigured

from django.db.models.fields.tuple_lookups import Tuple, TupleGreaterThan, TupleLessThan

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

class CursorPagination(pagination.CursorPagination):
    max_page_size = settings.MAXIMUM_PAGE_SIZE
    page_size = settings.DEFAULT_PAGE_SIZE
    page_size_query_param = 'page_size'
    offset_cutoff = 5000

    def __init__(self, results_key) -> None:
        self.results_key = results_key
        super().__init__()
    
    def encode_cursor(self, cursor):
        self.base_url = getattr(self, 'base_url', '')
        cursor_str = super().encode_cursor(cursor)
        urlp = urlparse.urlparse(cursor_str)
        query = urlparse.parse_qs(urlp.query)
        return query['cursor'][0]
    
    def __call__(self):
        return self.__class__(results_key=self.results_key)
    

    def get_paginated_response(self, data):
        return response.Response({
            'next': self.get_next_link(),
            'previous': self.get_previous_link(),
            'size': len(data),
            self.results_key: data,
        })

    def get_paginated_response_schema(self, schema):
        return {
            'type': 'object',
            'required': ['results'],
            'properties': {
                'next': {
                    'type': 'string',
                    'nullable': True,
                    'format': 'base64',
                    'example': self.encode_cursor(pagination.Cursor(offset=50, reverse=False, position=None)),
                },
                'previous': {
                    'type': 'string',
                    'nullable': True,
                    'format': 'base64',
                    'example': self.encode_cursor(pagination.Cursor(offset=500, reverse=True, position=None)),
                },
                'size': {
                    'type': 'integer',
                    'example': self.max_page_size,
                },
                self.results_key: schema,
            },
        }
    

    
class CompositeCursorPagination(CursorPagination):
    """
    Cursor pagination implementation based on composite (multi-column) ordering.

    This paginator extends DRF's CursorPagination to support lexicographic
    pagination using multiple ordered fields treated as a single composite key,
    e.g. (created, id).

    Unlike standard cursor pagination, which treats ordering as a flat sequence,
    this implementation:

    - Enforces consistent ordering direction across all fields (all ASC or all DESC)
    - Uses tuple-based comparisons for cursor filtering
    - Preserves stable, deterministic ordering suitable for large datasets
    - Supports composite index-friendly pagination patterns

    The cursor position is encoded as a split string representing each ordered
    field value, allowing reconstruction of a multi-column position boundary.

    This approach is designed for high-performance pagination over datasets
    where a composite database index exists matching the ordering fields.

    Notes:
        - Mixed ascending/descending ordering is not supported.
        - Ordering must align with a composite B-tree index for optimal performance.
        - Cursor comparison relies on lexicographic tuple semantics.
    """

    def _get_position_from_instance(self, instance, ordering):
        position = []
        for field_name in ordering:
            field_name = field_name.lstrip('-')
            position.append(self._get_field_value(instance, field_name))
        return self._encode_position(position)
    
    def _encode_position(self, position: list[str]) -> str:
        return urlparse.urlencode(dict(zip(range(len(position)),position)))
    
    def _decode_position(self, position) -> list[str]:
        data = urlparse.parse_qsl(position)
        position = []
        for _, pos in sorted(data, key=lambda x: x[0]):
            position.append(pos)
        return position

    
    def _get_field_value(self, instance, field_name):
        if isinstance(instance, dict):
            attr = instance[field_name]
        else:
            attr = getattr(instance, field_name)
        return str(attr)
    
    def validate_ordering(self, ordering: tuple[str]):
        """
        Ensures tuple pagination is safe:
        - all fields must have same direction
        - no mixed asc/desc ordering allowed
        """

        if not ordering:
            raise ImproperlyConfigured("Ordering must be defined for cursor pagination")

        directions = {field.startswith("-") for field in ordering}

        if len(directions) != 1:
            raise ImproperlyConfigured(
                f"Mixed ordering directions are not supported for tuple pagination: {ordering}"
            )
    
    def paginate_queryset(self, queryset, request, view=None):
        self.request = request
        self.page_size = self.get_page_size(request)
        if not self.page_size:
            return None

        self.base_url = request.build_absolute_uri()
        self.ordering = self.get_ordering(request, queryset, view)
        self.validate_ordering(self.ordering)

        self.cursor = self.decode_cursor(request)
        if self.cursor is None:
            (offset, reverse, current_position) = (0, False, None)
        else:
            (offset, reverse, current_position) = self.cursor

        # Cursor pagination always enforces an ordering.
        if reverse:
            queryset = queryset.order_by(*pagination._reverse_ordering(self.ordering))
        else:
            queryset = queryset.order_by(*self.ordering)

        # If we have a cursor with a fixed position then filter by that.
        if current_position is not None:
            queryset = self.filter_from_current_position(queryset, current_position)

        # If we have an offset cursor then offset the entire page by that amount.
        # We also always fetch an extra item in order to determine if there is a
        # page following on from this one.
        results = list(queryset[offset:offset + self.page_size + 1])
        self.page = list(results[:self.page_size])

        # Determine the position of the final item following the page.
        if len(results) > len(self.page):
            has_following_position = True
            following_position = self._get_position_from_instance(results[-1], self.ordering)
        else:
            has_following_position = False
            following_position = None

        if reverse:
            # If we have a reverse queryset, then the query ordering was in reverse
            # so we need to reverse the items again before returning them to the user.
            self.page = list(reversed(self.page))

            # Determine next and previous positions for reverse cursors.
            self.has_next = (current_position is not None) or (offset > 0)
            self.has_previous = has_following_position
            if self.has_next:
                self.next_position = current_position
            if self.has_previous:
                self.previous_position = following_position
        else:
            # Determine next and previous positions for forward cursors.
            self.has_next = has_following_position
            self.has_previous = (current_position is not None) or (offset > 0)
            if self.has_next:
                self.next_position = following_position
            if self.has_previous:
                self.previous_position = current_position

        # Display page controls in the browsable API if there is more
        # than one page.
        if (self.has_previous or self.has_next) and self.template is not None:
            self.display_page_controls = True

        return self.page
    
    def filter_from_current_position(self, queryset, cursor_position):
        order = self.ordering[0]
        is_reversed = order.startswith('-')
        positions = self._decode_position(cursor_position)
        attrs = [(order_attr.lstrip('-')) for order_attr in self.ordering]
        if self.cursor.reverse !=  is_reversed:
            op_filter = TupleLessThan(Tuple(*attrs), positions)
        else:
            op_filter = TupleGreaterThan(Tuple(*attrs), positions)
        return queryset.filter(op_filter)