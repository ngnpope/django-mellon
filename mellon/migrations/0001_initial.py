# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserSAMLIdentifier',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('issuer', models.TextField(verbose_name='Issuer')),
                ('name_id', models.TextField(verbose_name='SAML identifier')),
                ('created', models.DateTimeField(auto_now_add=True, verbose_name='created')),
                ('user', models.ForeignKey(related_name='saml_identifiers', verbose_name='user', to=settings.AUTH_USER_MODEL, on_delete=models.CASCADE)),
            ],
            options={
                'verbose_name': 'user SAML identifier',
                'verbose_name_plural': 'users SAML identifiers',
            },
            bases=(models.Model,),
        ),
        migrations.AlterUniqueTogether(
            name='usersamlidentifier',
            unique_together=set([('issuer', 'name_id')]),
        ),
    ]
