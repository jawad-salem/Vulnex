import uuid
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('engagements', '0004_client_default_report_template'),
        ('recon', '0003_reconscan_pipeline'),
        ('vulns', '0010_finding_comment'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AttackPath',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=200)),
                ('description', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('engagement', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='attack_paths', to='engagements.engagement',
                )),
                ('created_by', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='created_attack_paths',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={'ordering': ['-created_at']},
        ),
        migrations.CreateModel(
            name='AttackPathNode',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('label', models.CharField(max_length=200)),
                ('kind', models.CharField(
                    choices=[
                        ('entrypoint', 'Entry Point'),
                        ('host', 'Host'),
                        ('identity', 'Identity'),
                        ('asset', 'Asset'),
                        ('objective', 'Objective'),
                    ],
                    default='host', max_length=20,
                )),
                ('notes', models.TextField(blank=True)),
                ('position_x', models.IntegerField(default=0)),
                ('position_y', models.IntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('path', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='nodes', to='engagements.attackpath',
                )),
                ('discovered_host', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='attack_path_nodes',
                    to='recon.discoveredhost',
                )),
            ],
            options={'ordering': ['created_at']},
        ),
        migrations.CreateModel(
            name='AttackPathEdge',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('technique', models.CharField(
                    help_text='Free-form technique label, e.g. "Pass-the-Hash", "Kerberoast".',
                    max_length=200,
                )),
                ('mitre_attack_id', models.CharField(
                    blank=True,
                    help_text='Optional MITRE ATT&CK technique ID, e.g. T1078.',
                    max_length=20,
                )),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('path', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='edges', to='engagements.attackpath',
                )),
                ('from_node', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='outgoing_edges',
                    to='engagements.attackpathnode',
                )),
                ('to_node', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='incoming_edges',
                    to='engagements.attackpathnode',
                )),
                ('finding', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='attack_path_edges',
                    to='vulns.finding',
                )),
            ],
            options={'ordering': ['created_at']},
        ),
        migrations.AddConstraint(
            model_name='attackpathedge',
            constraint=models.CheckConstraint(
                check=models.Q(_negated=True, from_node=models.F('to_node')),
                name='attackpathedge_no_self_loop',
            ),
        ),
    ]
