from django import template

register = template.Library()


@register.filter
def get_checklist(progress_dict, item_id):
    """Look up an EngagementChecklist from the progress dict by checklist_item id."""
    return progress_dict.get(item_id)
