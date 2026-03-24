"""module permettant de detecter les batch anormaux"""
from sklearn.ensemble import IsolationForest
from detection.rules import Alert
from config import ModelNotTrainedError

class Ml_detector():
    """gere la detetion d'attaque par isolation forest"""
    def __init__(self):
        self.forest = IsolationForest()
        self.has_been_trained = False

    # ======================== Entrainement du modèls ========================
    def fit(self, sample_list):
        """entraine le medèls"""
        if len(sample_list) < 75:
            raise ValueError("pas assez de données pour entraîner (cible: 75 sample)")
        self.forest.fit([batch.to_vector() for batch in sample_list])
        self.has_been_trained = True


    # ======================== Prédiction ========================
    def est_anomalie(self, score):
        """renvoie true si le score donnée correspond a une anomalie"""
        return score != 1

    def predict(self, batch) -> Alert | None:
        """donne une valeur de risque d'attaque dans le batch"""
        if self.has_been_trained is not True:
            raise ModelNotTrainedError("le modèle doit être entraîné avant de prédire")

        result = self.est_anomalie(
            self.forest.predict([batch.to_vector()])[0] #predict renvoie [score] donc on utilise [0]
            )

        if result:
            # alert = batch.find_suspect() #FIXME find_suspect pas implementer
            # return alert

            return Alert(
                None, #alert_type et
                None, # src_ip vont venir avec find-suspect
                None, #FIXME severiter pas implementer
                batch.batch.timestamp_start
            )

        else:
            return None
