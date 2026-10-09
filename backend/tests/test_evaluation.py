from app.services.evaluation import evaluate, dataset, metrics


def test_evaluation_selects_on_training_and_reports_heldout_errors():
    result=evaluate()
    selected=max(result['candidate_training_metrics'],key=lambda row:(row['f1'],row['threshold_days']))
    assert result['selected_threshold_days']==selected['threshold_days']
    snap,labels=dataset(result['heldout_seed'])
    assert result['heldout_selected']==metrics(snap,labels,selected['threshold_days'])
    assert result['heldout_selected']['false_positive']+result['heldout_selected']['false_negative']>0
    assert result==evaluate()


def test_independent_splits_have_different_observations():
    train,labels=dataset(117);heldout,other=dataset(811)
    assert train.digest!=heldout.digest and labels!=other
