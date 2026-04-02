from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse
from engagements.models import Engagement, ActivityLog
from .models import Report
from .generator import generate_report_pdf
from accounts.decorators import engagement_access, engagement_edit_required


@login_required
@engagement_access(allow_client=True)
def report_dashboard(request, engagement_pk):
    engagement = request.engagement
    reports = engagement.reports.all()
    context = {
        'engagement': engagement,
        'reports': reports,
        'can_generate': request.eng_role in ('admin', 'lead', 'pentester'),
    }
    return render(request, 'reports/dashboard.html', context)


@login_required
@engagement_edit_required
def generate_report(request, engagement_pk):
    engagement = request.engagement
    report_type = request.POST.get('report_type', 'full')

    pdf_bytes = generate_report_pdf(engagement, report_type)

    report = Report.objects.create(
        engagement=engagement,
        title=f'{engagement.name} — {dict(Report.ReportType.choices).get(report_type, "Report")}',
        report_type=report_type,
        generated_by=request.user,
    )

    from django.core.files.base import ContentFile
    import re
    safe_name = re.sub(r'[^\w\-]', '_', engagement.name)
    filename = f'pentest_report_{safe_name}_{report_type}.pdf'
    report.file.save(filename, ContentFile(pdf_bytes))

    ActivityLog.objects.create(
        engagement=engagement, user=request.user,
        action=f'Generated {report.get_report_type_display()} report'
    )
    messages.success(request, 'Report generated successfully.')
    return redirect('reports:dashboard', engagement_pk=engagement_pk)


@login_required
def download_report(request, pk):
    report = get_object_or_404(Report.objects.select_related('engagement'), pk=pk)
    if not report.engagement.user_can_access(request.user):
        messages.error(request, 'You are not a member of this engagement.')
        return redirect('engagements:list')
    response = HttpResponse(report.file.read(), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{report.file.name.split("/")[-1]}"'
    return response


@login_required
@engagement_access(allow_client=True)
def preview_report(request, engagement_pk):
    engagement = request.engagement
    report_type = request.GET.get('type', 'full')
    pdf_bytes = generate_report_pdf(engagement, report_type)

    response = HttpResponse(pdf_bytes, content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="preview.pdf"'
    return response
