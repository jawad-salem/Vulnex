from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('recon', '0001_initial'),
        ('vulns', '0002_finding_endpoint_finding_host_finding_http_method_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='finding',
            name='discovered_host',
            field=models.ForeignKey(
                blank=True,
                help_text='Link to a discovered host from recon',
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='findings',
                to='recon.discoveredhost',
            ),
        ),
        migrations.CreateModel(
            name='FindingTemplate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200, unique=True)),
                ('title', models.CharField(max_length=300)),
                ('severity', models.CharField(choices=[('critical', 'Critical'), ('high', 'High'), ('medium', 'Medium'), ('low', 'Low'), ('info', 'Informational')], max_length=20)),
                ('description', models.TextField()),
                ('remediation', models.TextField(blank=True)),
                ('references', models.TextField(blank=True)),
                ('cwe_id', models.CharField(blank=True, max_length=20)),
                ('attack_vector', models.CharField(default='N', max_length=1)),
                ('attack_complexity', models.CharField(default='L', max_length=1)),
                ('privileges_required', models.CharField(default='N', max_length=1)),
                ('user_interaction', models.CharField(default='N', max_length=1)),
                ('confidentiality_impact', models.CharField(default='N', max_length=1)),
                ('integrity_impact', models.CharField(default='N', max_length=1)),
                ('availability_impact', models.CharField(default='N', max_length=1)),
            ],
            options={
                'ordering': ['name'],
            },
        ),
    ]
