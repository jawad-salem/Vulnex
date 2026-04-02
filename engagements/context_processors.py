def engagement_role(request):
    """Add the user's engagement role and engagement object to template context."""
    if not hasattr(request, 'user') or not request.user.is_authenticated:
        return {}

    ctx = {}
    # These are set by the engagement_access / engagement_edit_required decorators
    if hasattr(request, 'eng_role'):
        ctx['eng_role'] = request.eng_role
        ctx['is_client_role'] = request.eng_role == 'client'
    if hasattr(request, 'engagement'):
        ctx['engagement'] = request.engagement
    return ctx
