"""Seeded policy-threshold evaluation against synthetic lifecycle labels, without API calls."""
import argparse
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import random
from app.domain.analysis import analyze
from app.domain.imports import load_snapshot
from app.domain.models import Policy


def dataset(seed: int, count=200):
    rng = random.Random(seed)
    observed = datetime(2026, 10, 1, tzinfo=timezone.utc)
    identities = []
    labels = {}
    for n in range(count):
        retired = rng.random() < .35
        enabled = rng.random() >= .1
        # Deliberately overlapping activity: legitimate seasonal users can be dormant,
        # and departed users may have recently used their account before leaving.
        days = rng.randint(45, 240) if retired else rng.randint(0, 130)
        id_ = f'synthetic-{n:04d}'
        labels[id_] = retired and enabled
        identities.append({'id': id_, 'display_name': f'Synthetic identity {n}', 'kind': 'human',
                           'enabled': enabled, 'created_at': '2025-01-01T00:00:00Z',
                           'last_login': (observed-timedelta(days=days)).isoformat(), 'mfa': True,
                           'roles': [], 'groups': []})
    data = {'observed_at': observed.isoformat(), 'roles': [], 'groups': [], 'identities': identities}
    return load_snapshot(json.dumps(data).encode()), labels


def metrics(snapshot, labels, days):
    result = analyze(snapshot, replace(Policy(), stale_days=days))
    predicted = {f['identity_id'] for f in result['findings'] if f['rule'] == 'stale'}
    truth = {id_ for id_, label in labels.items() if label}
    tp, fp, fn = len(predicted & truth), len(predicted - truth), len(truth - predicted)
    precision = tp/(tp+fp) if tp+fp else 0
    recall = tp/(tp+fn) if tp+fn else 0
    f1 = 2*precision*recall/(precision+recall) if precision+recall else 0
    return {'threshold_days': days, 'true_positive': tp, 'false_positive': fp, 'false_negative': fn,
            'true_negative': len(labels)-tp-fp-fn, 'precision': round(precision, 4),
            'recall': round(recall, 4), 'f1': round(f1, 4)}


def evaluate():
    train, train_labels = dataset(117)
    heldout, heldout_labels = dataset(811)
    candidates = [metrics(train, train_labels, days) for days in (30, 60, 90, 120, 150, 180)]
    selected = max(candidates, key=lambda row: (row['f1'], row['threshold_days']))['threshold_days']
    return {'method': 'Synthetic stale-account policy calibration; not a trained threat detector',
            'training_seed': 117, 'heldout_seed': 811, 'identities_per_split': 200,
            'candidate_training_metrics': candidates, 'selected_threshold_days': selected,
            'heldout_default': metrics(heldout, heldout_labels, Policy().stale_days),
            'heldout_selected': metrics(heldout, heldout_labels, selected),
            'limitations': ['Labels represent synthetic lifecycle intent and are independent of the selected threshold.',
                           'The distributions overlap intentionally; inactivity alone cannot establish business need.',
                           'Held-out data is never used to select a threshold. No workspace policy is changed.',
                           'These results do not establish performance on real identity exports or evaluate LLM advice.']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    print(json.dumps(evaluate(), indent=2))
