import torch
import torch.nn as nn

class LSTMAdversarialMutator(nn.Module):
    def __init__(self, feature_dim=8, hidden_dim=64, seq_len=20, num_layers=2):
        super(LSTMAdversarialMutator, self).__init__()
        self.feature_dim = feature_dim
        self.hidden_dim = hidden_dim
        self.seq_len = seq_len
        self.num_layers = num_layers
        
        self.encoder = nn.LSTM(
            input_size=feature_dim, hidden_size=hidden_dim,
            num_layers=num_layers, batch_first=True,
            dropout=0.2 if num_layers > 1 else 0
        )
        
        self.decoder = nn.LSTM(
            input_size=hidden_dim, hidden_size=hidden_dim,
            num_layers=num_layers, batch_first=True,
            dropout=0.2 if num_layers > 1 else 0
        )
        
        self.output_layer = nn.Sequential(
            nn.Linear(hidden_dim, feature_dim),
            nn.Tanh()
        )

    def forward(self, x, mutation_intensity=0.1):
        batch_size = x.size(0)
        encoder_out, (hidden_state, cell_state) = self.encoder(x)
        noise = torch.randn_like(hidden_state) * mutation_intensity
        mutated_hidden_state = hidden_state + noise
        
        context_vector = mutated_hidden_state[-1].unsqueeze(1).repeat(1, self.seq_len, 1)
        decoder_out, _ = self.decoder(context_vector, (mutated_hidden_state, cell_state))
        mutated_traffic = self.output_layer(decoder_out)
        
        return mutated_traffic