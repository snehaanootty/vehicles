from django.http import HttpResponseForbidden
from django.utils.html import strip_tags

class XSSAndIPMiddleware:
    def _init_(self, get_response):
        self.get_response = get_response

    def _call_(self, request):
        request = self.handle_xss_attack(request)

                    
        if not self.is_ip_allowed(request):
            return HttpResponseForbidden('Access denied.')

        response = self.get_response(request)
        return response

    def handle_xss_attack(self, request):
        for key in request.POST:
            request.POST[key] = strip_tags(request.POST[key])

        return request

    def is_ip_allowed(self, request):
       
        allowed_ips = ['127.0.0.1', '192.168.0.1']
        client_ip = request.META.get('REMOTE_ADDR')

        if client_ip not in allowed_ips:
            return False

        return True