package com.example.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.DeleteOutline
import androidx.compose.material.icons.rounded.Error
import androidx.compose.material.icons.rounded.FolderZip
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.example.model.FodAnomaly
import com.example.model.FodSnapshot
import com.example.model.NodeStatus
import com.example.model.SeverityLevel
import com.example.ui.theme.AmberWarning
import com.example.ui.theme.CrimsonCritical
import com.example.ui.theme.CyanBiometric
import com.example.ui.theme.EmeraldVerified

@Composable
fun StatusPillBadge(
    label: String,
    color: Color,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(50),
        color = color.copy(alpha = 0.14f),
        border = BorderStroke(1.dp, color.copy(alpha = 0.45f))
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(7.dp)
                    .background(color, CircleShape)
            )
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                color = color,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
fun ScoreGaugeRing(
    score: Int,
    modifier: Modifier = Modifier,
    size: Dp = 88.dp
) {
    val ringColor = when {
        score >= 80 -> EmeraldVerified
        score >= 50 -> AmberWarning
        else -> CrimsonCritical
    }
    val trackColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)

    Box(
        modifier = modifier.size(size),
        contentAlignment = Alignment.Center
    ) {
        Canvas(modifier = Modifier.size(size)) {
            val strokeWidth = 8.dp.toPx()
            drawArc(
                color = trackColor,
                startAngle = 0f,
                sweepAngle = 360f,
                useCenter = false,
                style = Stroke(width = strokeWidth, cap = StrokeCap.Round)
            )
            drawArc(
                color = ringColor,
                startAngle = -90f,
                sweepAngle = (score.coerceIn(0, 100) / 100f) * 360f,
                useCenter = false,
                style = Stroke(width = strokeWidth, cap = StrokeCap.Round)
            )
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = "$score%",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = ringColor
            )
            Text(
                text = "Intégrité",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun AnomalyCard(
    anomaly: FodAnomaly,
    modifier: Modifier = Modifier
) {
    val accent = severityColor(anomaly.severity)
    val icon = when (anomaly.severity) {
        SeverityLevel.CRITIQUE -> Icons.Rounded.Error
        SeverityLevel.AVERTISSEMENT -> Icons.Rounded.Warning
        SeverityLevel.INFO -> Icons.Rounded.Info
        SeverityLevel.CONFORME -> Icons.Rounded.CheckCircle
    }

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        border = BorderStroke(1.dp, accent.copy(alpha = 0.45f))
    ) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(imageVector = icon, contentDescription = anomaly.severity.labelFr, tint = accent, modifier = Modifier.size(20.dp))
                Text(
                    text = anomaly.title,
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f)
                )
                StatusPillBadge(label = anomaly.severity.labelFr, color = accent)
            }
            Text(
                text = "Couche : ${anomaly.layer.labelFr}",
                style = MaterialTheme.typography.labelSmall,
                color = CyanBiometric
            )
            Surface(
                shape = MaterialTheme.shapes.small,
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.7f)
            ) {
                Text(
                    text = anomaly.evidence,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.padding(10.dp)
                )
            }
            Text(
                text = "Impact : ${anomaly.impact}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = "Action de portage : ${anomaly.portingAction}",
                style = MaterialTheme.typography.bodySmall,
                color = EmeraldVerified
            )
        }
    }
}

@Composable
fun SnapshotCard(
    snapshot: FodSnapshot,
    isActive: Boolean,
    onOpenDashboard: () -> Unit,
    onDelete: () -> Unit,
    modifier: Modifier = Modifier
) {
    val meta = snapshot.metadata
    val border = if (isActive) {
        BorderStroke(1.5.dp, CyanBiometric)
    } else {
        BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.6f))
    }

    Card(
        onClick = onOpenDashboard,
        modifier = modifier
            .fillMaxWidth()
            .testTag("snapshot_card_${meta.id}"),
        shape = MaterialTheme.shapes.medium,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = border
    ) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Rounded.FolderZip,
                    contentDescription = "Capture FOD",
                    tint = if (meta.isImported) AmberWarning else CyanBiometric,
                    modifier = Modifier.size(22.dp)
                )
                Spacer(Modifier.width(10.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = meta.displayName,
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = "${meta.id} • ${meta.timestampIso}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                IconButton(
                    onClick = onDelete,
                    modifier = Modifier
                        .minimumInteractiveComponentSize()
                        .testTag("delete_snapshot_${meta.id}")
                ) {
                    Icon(
                        imageVector = Icons.Rounded.DeleteOutline,
                        contentDescription = "Supprimer cette capture",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatusPillBadge(
                    label = meta.romType.labelFr,
                    color = if (meta.isDsuActive) AmberWarning else EmeraldVerified
                )
                StatusPillBadge(
                    label = "Score ${meta.completenessScore}%",
                    color = CyanBiometric
                )
                StatusPillBadge(
                    label = "${snapshot.artifacts.size} artefacts",
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

fun severityColor(level: SeverityLevel): Color = when (level) {
    SeverityLevel.CRITIQUE -> CrimsonCritical
    SeverityLevel.AVERTISSEMENT -> AmberWarning
    SeverityLevel.INFO -> CyanBiometric
    SeverityLevel.CONFORME -> EmeraldVerified
}

fun nodeStatusColor(status: NodeStatus): Color = when (status) {
    NodeStatus.ACTIF -> EmeraldVerified
    NodeStatus.PATCH_CONSTRUCTEUR -> CyanBiometric
    NodeStatus.MANQUANT -> AmberWarning
    NodeStatus.CASSE -> CrimsonCritical
    NodeStatus.PROTEGE -> Color(0xFF90A4AE)
}
