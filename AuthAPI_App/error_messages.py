from django.http import JsonResponse


def error_message_401(message):
    return JsonResponse({
        "message": message
    }, status=401)